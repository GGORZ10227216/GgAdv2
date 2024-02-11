#include <emu_framework.h>

using namespace gg_core::gg_cpu;

#include <iostream>

#include <SDL2/SDL.h>
#include <shader_s.h>
#include <gg_texture.h>

enum class MEM_AREA { IO = 0, PALETTE, VRAM, OAM };

SDL_Window *gWindow = nullptr;
SDL_GLContext gContext;

int WIDTH = 720;
int HEIGHT = 480;

float vertices[] = {
	// positions          // colors           // texture coords
	1.0f, 1.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, // top right
	1.0f, -1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 1.0f, // bottom right
	-1.0f, -1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, // bottom left
	-1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f  // top left
};

unsigned int indices[] = {
	0, 1, 3, // first triangle
	1, 2, 3  // second triangle
};

bool Init() {
  bool success = true;

  if (SDL_Init(SDL_INIT_EVERYTHING) < 0) {
	fmt::print(stderr, "SDL could not be initialized! SDL_Error: {}", SDL_GetError());
	success = false;
  } // if
  else {
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);

	gWindow = SDL_CreateWindow(
		"GgAdv2",
		SDL_WINDOWPOS_UNDEFINED,
		SDL_WINDOWPOS_UNDEFINED,
		WIDTH,
		HEIGHT,
		SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN
	);

	if (!gWindow) {
	  fmt::print(stderr, "SDL Window could not be initialized! SDL_Error: {}", SDL_GetError());
	  success = false;
	} // if
	else {
	  gContext = SDL_GL_CreateContext(gWindow);
	  if (!gContext) {
		fmt::print(stderr, "OpenGL context could not be created! SDL_Error: {}", SDL_GetError());
		success = false;
	  } // if
	  else {
		if (SDL_GL_SetSwapInterval(1) < 0) {
		  fmt::print(stderr, "Warning: Unable to set VSync! SDL_Error: {}", SDL_GetError());
		} // if

		if (!gladLoadGLLoader((GLADloadproc) SDL_GL_GetProcAddress)) {
		  fmt::print(stderr, "GLAD could net be initialized!");
		  success = false;
		} // if
	  } // else
	} // else
  } // else

  return success;
} // Init()

int main(int argc, char **argv) {
//  gg_core::GbaInstance gbaInstance("./test.gba");
  /* DEBUG ONLY */
//  gbaInstance.StartMainLoop();
  /* DEBUG ONLY */
  if (Init()) {
    gg_core::GbaInstance gbaInstance(std::filesystem::absolute("./test.gba"));
	gg_gfx::PPU &ppu = gbaInstance.ppu;

	SDL_Event e;
	bool quit = false;

	gg_gfx::gg_texture _bgTex(240, 160);
	uint64_t fps = 0;

	Shader ourShader("texture.vs", "texture.fs");

	unsigned int VBO, VAO, EBO;
	glGenVertexArrays(1, &VAO);
	glGenBuffers(1, &VBO);
	glGenBuffers(1, &EBO);

	glBindVertexArray(VAO);

	glBindBuffer(GL_ARRAY_BUFFER, VBO);
	glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO);
	glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);

	// position attribute
	glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), (void *) 0);
	glEnableVertexAttribArray(0);
	// color attribute
	glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), (void *) (3 * sizeof(float)));
	glEnableVertexAttribArray(1);
	// texture coord attribute
	glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, 8 * sizeof(float), (void *) (6 * sizeof(float)));
	glEnableVertexAttribArray(2);

//	_sleep(3000);

	int frameCounter = 0;
	auto last = std::chrono::steady_clock::now();

	while (!quit) {
	  while (SDL_PollEvent(&e)) {
		if (e.type == SDL_QUIT) {
		  quit = true;
		} // if
	  } // while

	  gbaInstance.NextFrame();
//        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
//        glClear(GL_COLOR_BUFFER_BIT);
//
	  glBindTexture(GL_TEXTURE_2D, _bgTex.GetTextureId());
	  // method 1, pure software convert.
//        for (int y = 0 ; y < 160 ; ++y) {
//            uint32_t* rowStart = reinterpret_cast<uint32_t*>(_bgTex.GetRawDataXY(0, y)) ;
//            for (int x = 0 ; x < 240 ; ++x) {
//                uint16_t& input = _pPpu->frameBuffer[240*y + x] ;
//                uint8_t r, g, b, a;
//
//                r = (input & 0x1f) << 3 ;
//                g = (input & 0x3e0) >> 2 ;
//                b = (input & 0x7c00) >> 7 ;
//                a = 0xff ;
//
//                *rowStart = r | (g << 8) | (b << 16) | (a << 24) ;
//                ++rowStart ;
//            } // for
//        } // for
//
//        _bgTex.Update();

	  // method 2, send the raw RGBA5551 frameBuffer to GPU, let openGL deal with it (which is faster than method 1.)
	  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 240, 160, GL_RGBA, GL_UNSIGNED_BYTE, ppu.frameBuffer.data());
//        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 240, 160, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, _pPpu->frameBuffer.data());

	  ourShader.use();

	  glBindVertexArray(VAO);
	  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);

	  SDL_GL_SwapWindow(gWindow);
	} // while

	glDeleteVertexArrays(1, &VAO);
	glDeleteBuffers(1, &VBO);
	glDeleteBuffers(1, &EBO);
  } // if

  return 0;
} // main()
